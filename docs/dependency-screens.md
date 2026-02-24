# Dependency screens

When you open a dependency from a project (e.g. from the project’s Dependencies list), you get a set of tabs/screens focused on that dependency in the context of **this project**. This doc describes each screen.

---

## Overview screen

The **Overview** screen is the first tab. It answers the general questions: *Does this dependency work in our project?* and *What is it used for in this project?* Below is what you see on the screen and what it means.

### What the Overview is for

- **Does this dependency work in our project?** – Health and reputation (score, vulnerabilities, license vs project policy), whether it’s direct or transitive, and whether it’s actually used (e.g. “zombie” if it’s in package.json but not imported anywhere).
- **What is this used for in this project?** – Where it’s used: how many files import it, which other projects in your org use the same package, and (when available) an AI-generated summary of how it’s used (Aegis usage analysis).

From here you can open the Supply Chain or Watchtower tabs, or take actions like deprecating the package or creating a PR to remove or bump it.

---

### What’s on the screen

**Header (top)**

- **Package name and version** – e.g. `lodash @1.2.3`.
- **Links** – NPM (always), GitHub (if we have a repo URL).
- **License** – The license string plus an icon: ✓ compliant with project policy, ✗ violation, or ⚠ unknown/not in policy. If the project has no license policy, it just shows the license with a note.
- **Weekly downloads** – From npm, when we have it.
- **Reputation score** – A score out of 100 (green / yellow / red by range). Click it to open a **score breakdown** sidebar (OpenSSF-style factors, vulnerabilities, etc.).

**Description and Suggestion**

- **Description** – Package description from the registry, when available.
- **Suggestion** – For *direct* dependencies that are actually imported (not zombie), we show a “Suggestion” block:
  - **Using latest safe version** – You’re already on a version we consider safe (for the chosen severity).
  - **vX → vY** plus **Bump** – There’s a safer version; you can create a bump PR. If a bump PR already exists, you see **View PR** instead.
  - **No safe version** – We couldn’t find a version that meets the safety criteria.
  - If the dependency is a **zombie** (in package.json but not imported anywhere), the Suggestion block is hidden.

**Deprecation banner (when set)**

- If this package is deprecated (at org or team level), a yellow banner appears: “Deprecated by your organization” or “Deprecated by your team” and the recommended alternative. Users with org-level or team-level manage permission can **Remove Deprecation** (org-level users can remove org or team deprecations).

**Usage card**

- **Zombie package** – Direct dependency but *not imported in any file*. Shows “Zombie Package – Not imported in any file” and either **Create PR to Remove** or **View removal PR** if a removal PR already exists.
- **Direct, in use** – “Imported in N files · Used in M other projects across your org.” You can use **Have Aegis analyze usage** to get an AI summary of how it’s used; once run, that summary appears in an **Aegis Usage Analysis** section below (with an option to re-run).
- **Transitive** – “Transitive dependency — not directly imported.” No file count or removal PR; it’s brought in by another dependency.

**Actions (when allowed)**

- **Deprecate** – Mark this package as deprecated at org or team level and suggest an alternative (permission-gated by org or team manage).
- **Remove Deprecation** – Clear the deprecation (org-level users can remove org or team deprecations; team-level users can remove only team deprecations).
- **Create PR to Remove** / **View removal PR** – For zombie packages only.
- **Bump** / **View PR** – From the Suggestion block when a safer version exists. Bump scope (this project vs all in team vs all in org) depends on your permissions.

**Sidebars (opened by clicking)**

- **Score breakdown** – Opens when you click the reputation score; shows how the score is made up and vulnerability counts.
- **Deprecate** – Opens when you click Deprecate; form to enter the recommended alternative and submit (org or team scope depending on your permissions).

---

## Supply Chain screen

The **Supply Chain** tab is for managing which versions of this package are allowed and used across your **organization**, **team**, or **project**, and for inspecting vulnerabilities per version.

### What the Supply Chain screen is for

- **Manage versions at the right scope** – Depending on your permissions you can:
  - **Org** – Owners and users with “manage teams and projects” can ban versions and bump projects across the whole organization.
  - **Team** – Users with “manage projects” on a team (and no org-level manage) can ban versions and bump projects only for that team.
  - **Project** – Otherwise, you can only bump this project.
- **Ban versions** – Mark a specific version as banned so it’s excluded from “latest safe version” and (optionally) trigger bump PRs for projects currently on that version. Bans can be org-wide or team-wide; org-level users can remove any ban, team-level users can remove only team bans.
- **Bump to a safe version** – “Bump project” creates a PR for this project; “Bump all in team” or “Bump all in org” creates PRs for all projects in that scope that are not already on the target version.
- **Inspect vulnerabilities per version** – Switch the center node to any version in the dropdown to see that version’s vulnerability counts and status (Current, Banned, Quarantined, security checks). The graph shows the dependency tree for the selected version.

The screen helps you answer: *Which versions of this package are safe to use?*, *What’s banned or quarantined?*, and *What’s the best version to bump to for my team or org?*

### What’s on the screen

**Center node (package + version)**

- **Package name and selected version** – e.g. `lodash @5.10.0`. A **version dropdown** lists available stable versions in semver order (newest first). The current project version is labeled **Current**; banned versions show a **Banned** badge; quarantined (Watchtower) versions show **Quarantined**. Security check icons (registry, scripts, entropy) appear when the org has the package on Watchtower.
- **License** – Shown for the selected version when available.
- **Actions** – **Ban version** (opens sidebar; only if you have org or team manage). **Create PR** / **View PR** to bump this project to the selected version (when it’s not the current version and not banned).

**Latest safe version card**

- **Severity filter** – Choose which severity level to consider (critical / high / medium / low). “Latest safe” is the newest **stable** version (no beta/alpha/rc) that has no vulnerabilities at or above that severity for itself and its transitive dependencies, and that is not org- or team-banned for this project’s context.
- **Bump button** – Scope depends on permissions: **Bump project** (only this project), **Bump all in [team]** (all projects in the team), or **Bump all in org** (all projects in the organization). Creates PRs to the suggested safe version where applicable.

**Graph and table**

- **Dependency tree** – The center node is this package at the selected version; child nodes are its direct dependencies at the versions it declares. You can see the tree structure and, in the table below, vulnerability counts and details per dependency.
- **Vulnerabilities table** – Lists known vulnerabilities for the selected version (and its subtree when relevant), with severity, summary, and affected version ranges.

**Sidebars**

- **Ban version** – Pick a version to ban and the target version to bump to; submit to create the ban (org or team) and bump PRs for affected projects in that scope.
- **Remove ban** – Pick an existing ban (org or team) to remove; only if you have permission for that scope.

---

## Watchtower screen

The **Watchtower** tab is for **security and upstream monitoring**. It lets you add packages to Watchtower so your organization gets extra safety checks on those dependencies: registry integrity, install scripts analysis, and entropy analysis. Use it to look into supply-chain and upstream risks before CVEs exist.

### What the Watchtower screen is for

- **Security and upstream visibility** – See commits, contributors, and anomaly scores for the package’s source repo. Filter commits by “touches imported functions” for this project, clear commits as reviewed, and use Aegis to analyze individual commits.
- **Extra safety checks (when package is on Watchtower)** – For packages your org has added to Watchtower, each version is evaluated with:
  - **Registry integrity** – Compares the npm tarball to the package’s git source so you know the published artifact matches the repo.
  - **Install scripts** – Flags dangerous capabilities in lifecycle scripts (e.g. network access, shell execution).
  - **Entropy analysis** – Detects hidden or obfuscated payloads that may indicate malicious code.
- **Quarantine and version policy** – When a new release fails these checks or you choose to quarantine the next release, Watchtower can hold the new version in quarantine and use a “latest allowed” version for bump PRs. You can create bump or decrease PRs from the Watchtower screen.

Users with org-level “manage teams and projects” or team-level “manage projects” (owner team) can **enable** or **disable** Watchtower for a dependency. Enabling adds the package to the organization watchlist and kicks off analysis; disabling removes it from the watchlist (and from `watched_packages` if no other org watches it).

### What’s on the screen

**When not watching**

- **Watchtower Forensics** – Short description and an **Enable Watchtower** button. Feature cards describe: Registry Integrity, Install Script Analysis, Entropy Analysis, and Commit Anomaly Detection.

**When watching**

- **Header** – Package name, status (pending / analyzing / ready), and **Disable Watchtower** (or enable if currently off). Optional **Clear commits** to mark all current commits as reviewed (org-level).
- **Security checks** – Three status cards: Registry Integrity, Install Scripts, Entropy Analysis (pass / warning / fail and reason).
- **Version policy** – Latest allowed version, quarantine next release toggle, bump PR / decrease PR actions when applicable.
- **Commits list** – Recent commits with anomaly score, “touches imported functions” badge, and optional **Acknowledge** per commit. Filters: all vs touches imported; sort by recent or anomaly. Click a commit to open the commit sidebar (diff, Aegis analysis).
- **Sidebars** – Commit details (diff, Aegis), Version details (security checks per version).
