# fp-filter audit — Wave 10 engine relaxation coverage (2026-05-10)

## Context

Wave 10 (commits `c5b9ae3` + `5a28868`) deliberately broadened two Java sink
families to fix all-5/5 round-trip failures on jackson-databind and Log4j
CVEs in the 88-CVE benchmark:

- **Jackson** (`depscanner/src/taint-engine/framework-models/jackson.yaml`)
  now treats any tainted argument to `ObjectMapper.readValue`,
  `readerFor(...).readValue`, `convertValue`, `treeToValue`, or
  `JsonDeserializer.deserialize` as a `deserialization` sink — regardless of
  whether `enableDefaultTyping` / `activateDefaultTyping` / `@JsonTypeInfo`
  / `@JsonTypeIdResolver` / a polymorphic-target type / `BasicPolymorphicTypeValidator`
  is reachable. The Wave 10 header explicitly hands the gating responsibility
  to the fp-filter LLM stage.

- **Log4j** (`depscanner/src/taint-engine/framework-models/log4j.yaml`) now
  declares `argument_indices: []` on every per-level `Logger.<level>(*)` sink,
  so any tainted argument at any position fires the `code_injection` sink —
  even when the actual string never contains `${jndi:` / `${lower:jndi:` /
  `${env:` (i.e. cannot trigger the runtime lookup that powers Log4Shell).
  Wave 10 also acknowledges the engine cannot express `formatMsgNoLookups=true`
  / `log4j2.formatMsgNoLookups` runtime suppression — that gating is now
  owned by the fp-filter prompt too.

Both YAML headers contain the same instruction: "The fp-filter LLM stage
downstream is expected to suppress flows where [gate is missing]." This audit
checks whether the fp-filter prompt is actually capable of doing that.

## Location

Single unified module — fp-filter is NOT split between worker and backend.

- Implementation: `depscanner/src/taint-engine/fp-filter.ts`
- Jest tests: `depscanner/src/__tests__/taint-engine-fp-filter-triple.test.ts`
  (runs via the backend jest config — `roots` includes `../depscanner/src`)
- tsx smoke tests: `depscanner/test/taint-engine-fp-filter.test.ts`

The backend has no parallel implementation. The only call site is
`depscanner/src/taint-engine/runner.ts`, which feeds each engine-emitted Flow
whose deterministic confidence falls below the org threshold through
`filterFlow()`.

## Current prompt structure (pre-change)

`buildPrompt(flow, workspaceRoot, candidates, nonce)` emits a system prompt
+ user prompt. The system prompt today covers:

1. Output schema (one JSON object, triple shape).
2. `endpoint.classification` rubric (PUBLIC_UNAUTH / AUTH_INTERNAL /
   OFFLINE_WORKER / UNKNOWN — UNKNOWN gated to expensive Anthropic fallback).
3. `sanitization` cite-from-candidates rule + "zero candidates ⇒ false".
4. Untrusted-input nonce wrapper safety rules.

The user prompt feeds:

- `flow.vuln_class`, `flow.taint_kind`, `flow.entry_point_pattern`,
  `flow.sink_method`, `flow.sink_pattern`.
- Wrapped source / sink / sampled-intermediate snippets via `readSnippet`
  (line ± `SNIPPET_CONTEXT_LINES=4`, cap `MAX_SNIPPET_CHARS=1200`).
- Structured `candidate_sanitizers` list.
- The final "kept vs rejected — be CONSERVATIVE" prompt.

## Audit findings

### 1. Jackson gating: NOT COVERED

The prompt has zero language about:

- `enableDefaultTyping()` / `activateDefaultTyping()`
- `setPolymorphicTypeValidator(...)` / `BasicPolymorphicTypeValidator.builder()`
- `@JsonTypeInfo` / `@JsonTypeIdResolver` annotations
- The fact that `mapper.readValue(json, Foo.class)` with a concrete sealed
  type and NO default typing is NOT a gadget-chain RCE primitive
- The fact that a registered PTV makes the deserialisation SAFE even with
  default typing enabled

So when Wave 10 fires a Jackson `readValue` sink on a benign call shape
(e.g. `mapper.readValue(input, MyDto.class)` with no enabler in the project),
the prompt currently has no way to recognise this as a non-vulnerability.
The model can only fall back to the generic "be CONSERVATIVE; mark kept when
uncertain" instruction at the bottom — i.e. it will keep almost every
benign Jackson flow. **The Wave 10 promise that the fp-filter would gate
these is NOT met by today's prompt.**

The `SNIPPET_CONTEXT_LINES=4` window around the sink is also too narrow to
catch the enabler call, which typically lives in `ObjectMapper` construction
code (often a `@Bean` / `@Configuration` class elsewhere in the project).
Today this is acceptable because the fp-filter is told to look at the *source
and sink snippets only*, but for Jackson we need the model to consult the
sink-file imports and constructor neighborhood at minimum.

### 2. Log4j gating: NOT COVERED

The prompt has zero language about:

- `${jndi:` / `${lower:jndi:` / `${upper:jndi:` / `${env:` interpolation
  markers in the tainted string
- `formatMsgNoLookups=true` JVM flag / `log4j2.formatMsgNoLookups` system
  property
- The fact that `logger.info("User logged in: {}", userId)` with no
  `${...}` interpolation in the runtime string is NOT a Log4Shell-shape
  vulnerability — the Logger surface is broad but Log4Shell is specifically
  the lookup-evaluation primitive
- Log4j version cutoff (≥2.16 disables JNDI lookups; ≥2.17.1 fixes
  CVE-2021-44832)

So when Wave 10 fires `code_injection` on `logger.error("Failed", e)` because
`e` is tainted via an exception path, the prompt currently keeps the flow
regardless. **Same Wave 10 broken-promise as Jackson.**

### 3. Other Wave 10 / Wave 11 surfaces not yet covered

The prompt is also generic for these patterns:

- Generic Java stdlib `Runtime.exec(*)` / `ProcessBuilder` — the prompt
  doesn't know to look for `ArrayList<String>` argument splitting (which
  defangs shell injection) vs single-string exec.
- SSRF sinks (`HttpClient.send`, `URL.openConnection`) — the prompt doesn't
  know to look for allowlists / `InetAddress.isSiteLocalAddress()` gates.

These weren't part of this audit's scope but should be tracked as
follow-ups if Wave 11 / 12 introduces parallel sink relaxations.

## Recommendation (driving the next two commits)

Add two compact "FP-gating" sub-sections to the system prompt:

1. **Jackson deserialization gating.** Tell the model:
   - safe-pattern markers: no `enableDefaultTyping` / `activateDefaultTyping`
     anywhere in scope; PTV registered via `setPolymorphicTypeValidator`
     or `BasicPolymorphicTypeValidator.builder()`; target type is a concrete
     sealed/final class with no `@JsonTypeInfo`.
   - must-have-pattern markers: `enableDefaultTyping(...)`,
     `activateDefaultTyping(...)`, `@JsonTypeInfo`, `@JsonTypeIdResolver`,
     `Object.class` / `Map.class` / `List<?>` polymorphic target.
   - If none of the must-have markers are visible in the source/sink/
     intermediate snippets, MARK REJECTED.

2. **Log4j JNDI gating.** Tell the model:
   - safe-pattern markers: tainted string is a literal with no `${...}`
     interpolation; `formatMsgNoLookups=true` visible in config / system
     property; Log4j version ≥2.16.
   - must-have-pattern markers: `${jndi:` / `${lower:jndi:` / `${upper:jndi:`
     / `${env:` substring in the tainted argument's string-builder chain;
     attacker-controlled portion is concatenated into a `${...}` template.
   - If no `${...}` is visible in the tainted-string assembly path, MARK
     REJECTED.

Keep both sections to ≤8 lines each so the token budget per call stays
within the AICOST-1 ~4 KB context envelope documented in
`estimatePerFlowCostUsd`.

## Token-budget sanity check

The current system prompt is ≈30 lines (~150 tokens). Two 8-line gating
blocks add ≈80 tokens. Total system prompt grows to ~230 tokens — still
well under the 4 KB per-call envelope. No `MAX_OUTPUT_TOKENS` change needed.
