# Engine Extension Design Note: Property-Path Matching for Spring4Shell-Class CVEs

**Status:** Design only. No code in this pass.
**Scope:** Wave F triage of `CVE-2022-22965` (Spring4Shell) on the 88-CVE
iterate corpus, plus structural follow-up for any future CVE whose attack
shape is "tainted property-path string driving reflective setter walk."
**Companion doc:** `maven-recall-diagnosis.md` (which already deferred this
to engine work; this note pins down what that engine work would look like).

## TL;DR

The Spring4Shell AI fixture in `bench-iterate/v_base/2026-05-12T17-41-24/`
cannot be flipped by any spec-layer-only change for two independent
reasons:

1. **No sink modeled.** The engine has no `*.setPropertyValue(*)` sink
   today, and the diagnosis (`maven-recall-diagnosis.md` row CVE-2022-22965)
   already rejected adding one as blanket-FP territory.
2. **The fixture is structurally below the real CVE.** The AI emitted
   `wrapper.setPropertyValue("password", password)` with **string-literal
   property names** (`"name"`, `"password"`). The real CVE-2022-22965 attack
   is a property-path *string* like
   `class.module.classLoader.resources.context.parent.pipeline.first.pattern`,
   submitted by the attacker, walked recursively by Spring's
   `BeanWrapperImpl`. Detecting it requires inspecting the **content of the
   property-name string at the call site**, not just the taint state of
   either argument.

A throwaway probe (`scripts/probe-spring4shell.ts`, not committed) verified
both shapes — the AI fixture and a synthetic "tainted property-name string"
shape — emit `sources=2 sinks=0 flows=0` against the current spec set.

## What the engine would need

### Option A — `sink_property_paths` field on `FrameworkSink`

Augment `FrameworkSink` in `depscanner/src/taint-engine/spec.ts:113` with an
optional discriminator:

```ts
export interface FrameworkSink {
  pattern: string;
  vuln_class: VulnClass;
  argument_indices: number[];
  description: string;
  osv_id?: string;
  /**
   * Only present on sinks whose vulnerability is gated on the *content*
   * of a string-literal argument matching a property-path prefix. The
   * matcher inspects the call step's `argTexts[propertyPathArgIndex]`
   * (stripped of quotes) and fires only when one of the listed prefixes
   * matches.
   *
   * For Spring4Shell:
   *   pattern: "*.setPropertyValue(*)"
   *   argument_indices: [0]            # the property-name arg
   *   sink_property_paths: ["class.classLoader.", "class.module.classLoader."]
   *   property_path_arg_index: 0
   */
  sink_property_paths?: string[];
  property_path_arg_index?: number;
}
```

Matcher change (single new branch in `propagate-core.ts` sink-match path):

- After the standard `argument_indices` taint check, if
  `sink_property_paths` is set, look up
  `step.argTexts[property_path_arg_index]`.
- Strip surrounding `"`/`'` quotes. If the result starts with any of the
  listed prefixes (case-sensitive, dot-bounded), the sink fires; otherwise
  it suppresses.

The taint check is independent — the property-path predicate is an
*additional* filter, not a replacement. (Spring4Shell can fire even when
the *value* arg is a literal: the danger is the *path*.) So `argument_indices`
could legitimately be empty, in which case the sink fires purely on the
path predicate. That gives us a clean two-mode design:

| `argument_indices` | `sink_property_paths` | Behavior                                              |
| ------------------ | --------------------- | ----------------------------------------------------- |
| non-empty          | unset                 | today's taint-arg semantics                           |
| empty              | unset                 | today's "any tainted arg" semantics                   |
| any                | set                   | requires property-path prefix match; taint optional   |

### Option B — Source-side modeling of Spring's auto-binder

Instead of modeling `setPropertyValue` as a sink, model Spring's
`@ModelAttribute` / form-binding entry points as **sources whose taint kind
is `bean_property_path`**, then add a *sink* on any reflective getter chain
(`*.getClass().getClassLoader().*`, `*.getModule().getClassLoader().*`).
This catches the real CVE because the attack flows
`@ModelAttribute User → reflective walk through user.class.classLoader.*`.

This is closer to how Snyk Code / Endor model it. Cost: requires a new
`taint_kind` enum value AND a new IR shape — reflective getter chains
aren't single call patterns, they're property-access ladders. The Phase 6
engine deliberately lowers Java to call-shaped IR; member-access ladders
would need a new lowering case in `depscanner/src/taint-engine/java/ir.ts`.

### Option C — Sink as wildcard property-key match (cheapest, simplest)

A pared-back version of Option A: add `sink_property_paths` but **do not**
add taint-independence. Sink fires only when (a) one tainted argument is
present *and* (b) the property-name arg's string literal matches a prefix.
Property names submitted as variables (not literals) would not fire — but
in practice the LLM and real-world exploits both pass the path as a string
literal in the request body that Spring resolves to a literal binding key,
so this is acceptable until the first FN is observed.

This is the **recommended option** because it's the smallest delta against
the current engine and the predicate is well-typed (string literal vs.
arbitrary expression).

## Effort estimate (Option C)

| Layer                                 | Effort       | Files                                                                                |
| ------------------------------------- | ------------ | ------------------------------------------------------------------------------------ |
| Type extension                        | ~5 LOC       | `src/taint-engine/spec.ts`                                                           |
| YAML loader / validator               | ~20 LOC      | `src/taint-engine/spec-loader.ts`, `scripts/validate-taint-engine-specs.ts`          |
| Propagator branch                     | ~30 LOC      | `src/taint-engine/propagate-core.ts` (sink-match block)                              |
| `spring-beans.yaml` framework_model   | ~40 LOC      | `src/taint-engine/framework-models/spring-beans.yaml` (new)                          |
| Fixture pair + java.test.ts wiring    | ~80 LOC      | `test/taint-engine/fixtures/java-vulns/spring4shell-{vuln,safe}/`, `java.test.ts`    |
| AI fixture re-roll (separate concern) | LLM-side fix | `bench-iterate` prompt to emit the property-path shape, not the simple-key shape    |

Total: ~175 LOC engine + spec changes, plus a prompt/fixture revisit on the
bench-iterate side. The prompt fix is the **load-bearing** half — Option C
alone won't flip the existing AI fixture, because that fixture's property
names are literal-safe.

## Why this is out-of-scope for the current pass

Wave F lane discipline (Henry, 2026-05-12) forbids touching:

- `spec.ts` — required for the type addition
- `validate.ts` / `vuln-class-alias.ts` — required for YAML schema validation
- `propagate-core.ts` (sink-match block) — required for the new matcher branch

Any one of these is fine in isolation; landing all three together with
fixture coverage and benchmark verification is a Phase F deliverable on the
order of the xmlsec spec landed in `maven-recall-diagnosis.md` — not a
sub-agent scope.

## Concrete next step if Henry approves landing

1. Add `sink_property_paths` + `property_path_arg_index` to `FrameworkSink`
   in `spec.ts`. Update `validate.ts` to reject specs that set
   `property_path_arg_index` without `sink_property_paths` (and vice versa).
2. Add one branch to the sink-match logic in `propagate-core.ts` (between
   the existing `argument_indices` check and the flow emission).
3. Ship `framework-models/spring-beans.yaml`:

   ```yaml
   framework: spring-beans
   language: java
   version: "*"
   sources: []
   sinks:
     - pattern: "*.setPropertyValue(*)"
       vuln_class: code_injection
       argument_indices: [0]            # tainted property-name string
       property_path_arg_index: 0
       sink_property_paths:
         - "class.classLoader."
         - "class.module.classLoader."
         - "Class.classLoader."
       description: Spring BeanWrapper property-path RCE (CVE-2022-22965)
       osv_id: CVE-2022-22965
     - pattern: "*.setPropertyValues(*)"
       vuln_class: code_injection
       argument_indices: [0]
       property_path_arg_index: 0
       sink_property_paths:
         - "class.classLoader."
         - "class.module.classLoader."
       description: Spring DataBinder.setPropertyValues with reflective path
       osv_id: CVE-2022-22965
   sanitizers: []
   ```

4. Write a **vuln fixture** that uses the literal property-path string:

   ```java
   @RequestMapping("/exploit")
   public String pwn(@RequestParam("attackerPath") String attackerPath,
                    @RequestParam("v") String v) {
     BeanWrapperImpl w = new BeanWrapperImpl(new User());
     // Direct exploitation: attacker controls both arg0 (path) and arg1 (value).
     // Real Spring4Shell auto-binds, but this is the modelable subset.
     w.setPropertyValue("class.module.classLoader.resources.context.parent.pipeline.first.pattern", v);
     return "ok";
   }
   ```

   This shape exercises Option C: tainted `v`, literal property-name arg
   that starts with `class.module.classLoader.`.

5. Write a **safe fixture** that calls `setPropertyValue("password", v)`
   — same taint flow, but the literal property-name string fails the
   prefix predicate, so no flow fires. This proves Option C narrows the
   FP surface.

## What this does NOT cover

- The actual Spring4Shell exploit chain (auto-binding via `@ModelAttribute`
  / form binders without any explicit `setPropertyValue` call) requires
  Option B — modeling Spring's auto-binder as a source-side construct, AND
  inferring reflective walks from accessor chains on the bound POJO. That
  is genuinely a multi-pass engine effort and not unlocked by Option C.

- The current AI fixture for CVE-2022-22965 in the bench-iterate corpus
  has *literal property-name args of safe shape* (`"name"`, `"password"`).
  Even with Option C landed, the existing fixture will still emit zero
  flows because the literal arg won't match any of the path prefixes. The
  iterate-side fix is to revise the LLM prompt to emit the property-path
  shape — independently of any engine work.

## Decision recommended

Land Option C in a **dedicated Phase F-2 pass** (separate worktree, single
agent) once Wave F's parallel sub-agents merge. Two artifacts gate go/no-go:

- A real-world fixture corpus survey (grep Maven Central / GHSA write-ups
  for the actual exploit form) — confirm the literal-property-path-string
  shape is the dominant form in the wild, not just an artifact of one
  Spring version.
- A FP audit on a sample of 5-10 large Spring projects (e.g., Spring PetClinic,
  Eureka, Cloud Config Server) running the new spec to confirm the
  `class.classLoader.` / `class.module.classLoader.` prefixes never appear
  as legitimate `setPropertyValue` first-arg literals in production code.
  If both prefixes are unique-to-exploit, the spec is safe to land. If
  not, narrow the prefix or move to Option B.
