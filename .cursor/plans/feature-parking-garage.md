# 🅿️ Feature Parking Garage

Features that were built (in whole or part) but are being **shelved, not killed** — parked
because they're not earning their place *right now*, with the rationale preserved so the
decision can be revisited intentionally later (instead of rediscovered from scratch).

Each entry records: what it is, why it's parked, what we're doing about it now, when to
revisit, and how cheap it is to revive.

---

## Project importance (asset-criticality multiplier)

**Parked:** 2026-06-16

**What it is.** A per-project `projects.importance` scalar in `[0.5, 2.0]` (default `1.0`)
that is multiplied directly into every finding's depscore as `tierWeight`
(`calculateDepscore` in `depscanner/src/depscore.ts`). It was itself a simplification of an
earlier, heavier model — the `asset_tier` enum + `organization_asset_tiers` table, dropped
in `phase41_drop_asset_tiers.sql`. Surfaced as an `ImportanceSlider` card in the project
sidebar General settings + a control in the create-project flow.

**Why it's parked.**
- **Low leverage.** Reachability (confirmed / data_flow / function / module) is Deptex's
  actual prioritization engine. Importance is the least-principled input in the score — a
  coarse, manual, linear multiplier sitting on top of the real signal.
- **Almost always the default.** It ships at `1.0` (a no-op) and realistically very few
  users will tune a 0.5–2.0 dial per project. Most of the time it does nothing while still
  costing UI + pipeline + mental overhead.
- **Interpretability tax.** Two findings for the *same CVE at the same reachability* can
  show different depscores purely because a human moved a slider — confusing.
- **Half-built.** Changing importance does **not** recompute the stored finding depscores —
  they're baked at scan time (`pipeline-steps/importance.ts` → `dep-scan.ts` /
  `reachability.ts` → stored in `project_dependency_vulnerabilities.depscore`). The
  `PUT /projects/:id` handler only writes the column; the backend recompute was never built.
  So even when someone *does* set it, nothing re-scores until the next scan.

**What we're doing now.** Removing the two UI **entry points** (General-settings card +
create-project flow) and leaving the column at its `1.0` default. With importance `= 1.0`
everywhere, `tierWeight` is a neutral multiplier, so the depscore math is an exact no-op and
the backend / pipeline / formula are left **untouched** (no scoring churn — we already
simplified this surface once). See the removal plan: `.cursor/plans/remove-project-importance.plan.md`.

**When to revisit.** As part of the **org compliance + policy + scoring engine** arc
(`feature-brief-org-compliance-policy-engine.md`). Asset criticality genuinely belongs in
the coherent "one score / a few scores" design — ideally derived from policy or asset
metadata, not a raw slider bolted onto project settings. Revisit it there, deliberately.

**Revival cost.** Cheap. The column, the `tierWeight` formula, and the whole depscore
pipeline stay intact — reviving is "re-add a UI surface + (this time) build the
recompute-on-change." The hard part (the scoring math) is already done and proven.
