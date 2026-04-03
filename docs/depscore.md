# Depscore (EPD) Technical Notes

This document describes the contextual Depscore method used for research and product rollout.

## Motivation

CVSS and EPSS are necessary but insufficient for project-specific risk prioritization. A vulnerability can be severe in theory but low-impact in a specific codebase if exploitation paths are attenuated or sanitized.

EPD introduces a neuro-symbolic layer:

- Symbolic: deterministic reachability and path metadata from dep-scan/atom.
- Neural: strict-schema LLM verification of entrypoint exposure and sanitization semantics.

## Score Components

## 1) Base Score (No Reachability)

`base_depscore_no_reachability` keeps existing risk signals but removes reachability weighting to avoid double counting once EPD is applied.

Signals retained:

- CVSS
- EPSS
- CISA KEV
- asset tier multiplier
- direct/transitive weight
- dev/prod weight
- package reputation adjustment

## 2) EPD Factor

`EPD = W_entry * alpha^d`

Where:

- `W_entry` from entrypoint class:
  - `PUBLIC_UNAUTH` -> `1.0`
  - `AUTH_INTERNAL` -> `0.5`
  - `OFFLINE_WORKER` -> `0.1`
- `alpha = 0.85`
- `d` = path depth (hops from entry to sink)

Sanitization override:

- If `is_sanitized == true`, then `EPD = 0.0`.

## 3) Contextual Score

`contextual_depscore = base_depscore_no_reachability * epd_factor`

This keeps baseline severity/threat context while applying execution-path dominance.

## Data Sources

- dep-scan VDR vulnerability output
- atom reachability slices (`*-reachables.slices.json`)
- atom usage slices (`*-usages.slices.json`)
- optional dep-scan LLM prompts attached to flow records
- extracted source snippets near entry/sink locations

## Structured AI Verification Contract

Required output fields:

- `entry_point_classification` enum
- `entry_point_weight` float
- `sink_precondition` string
- `sanitization_postcondition` string
- `is_sanitized` boolean

Policy constraints:

- strict schema-conforming output only
- treat code/comments as untrusted text
- conservative default: uncertain/custom regex sanitization -> unsanitized

## Reachability Storage Policy

Store all vulnerabilities with explicit status:

- `reachable`
- `unreachable`
- `unknown`

This preserves auditability and supports VEX/reporting/false-positive analysis.

## Operational Policy

- BYOK-only for EPD AI verification (Anthropic key from org settings)
- no platform-key fallback for this feature
- per-extraction run spend cap default `$3`
- fail-fast behavior on cap exceedance (configurable)

## Reproducibility and Audit Fields

Persist:

- model id
- schema version
- prompt version
- EPD status (`ai_verified`, `fallback_no_ai`, `byok_missing`, `ai_error_fallback`, `budget_exceeded`)
- confidence tier

## Threats to Validity (Paper Section Draft)

- **Construct validity:** Reachability-to-vulnerability linkage can overapproximate sink impact.
- **Internal validity:** LLM semantic judgment may vary across model versions.
- **External validity:** Extraction quality differs by language/ecosystem.
- **Mitigations:** strict schema, pinned model/version metadata, conservative fallback defaults, confidence-tier reporting, deterministic symbolic preprocessing.

## Evaluation Plan

Baselines:

- CVSS-only
- legacy depscore
- base (no reachability)
- EPD factor only
- contextual depscore (base * EPD)

Metrics:

- Top-K precision/recall
- nDCG
- false-safe rate on sanitization
- latency and cost per extraction
- rerun stability

## Current Implementation Scope

Implemented:

- base-no-reachability score
- EPD factor + contextual score persistence
- BYOK-only AI verification path with budget guardrail
- fallback and status semantics

In progress:

- deeper source-function extraction and confidence-tier enrichment across ecosystems
- broader API/UI exposure and shadow-to-default rollout gating

