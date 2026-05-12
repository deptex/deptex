# Maven Recall Diagnosis — 88-CVE Iterate Corpus, 2026-05-12

## Headline

The 88-CVE iterate harness at tip `846beeb` (after the commons-text spec
landed in `be17571`) reports **10/16 maven CVEs validated = 62.5%**. The
2026-05-12 17:41 v_base run summary lists `CVE-2022-42889` (Text4Shell) as
`validated`, contradicting the carried-forward triage note that flagged
it as a non-flip. A direct engine probe (`scripts/probe-java-fixtures.ts`)
confirms the spec actually does fire on the AI-generated fixture:

```
CVE-2022-42889  flowsEmitted=1  vuln_class=code_injection
                pattern=StringSubstitutor.replace(*)  flow_length=2
```

**No Text4Shell fix is needed** — the `commons-text.yaml` spec from
`be17571` already covers the Qwen fixture
(`StringSubstitutor.replace(template, System::getenv)` — 2-arg overload,
tainted arg at index 0). The pre-Phase-ABCD triage was generated against
an older tip that pre-dated the spec, hence the stale entry.

The roadmap maven target was 63% → ~80%. This document walks the six
remaining failures, identifies the **one** that yields to a new
framework_model (`xmlsec.yaml`, landed in this pass — see fixture and
spec below), and classifies the other five as deferred or uncatchable.

## Per-CVE status

| CVE | Package | Roadmap label | Engine verdict | Action |
|---|---|---|---|---|
| CVE-2022-42889 | `org.apache.commons/commons-text` | `no_flows_source_present` (stale) | **`flowsEmitted=1`** — fires on the 2-arg `StringSubstitutor.replace(...)` overload via the Phase-B `commons-text.yaml`. | **Already covered**; no change. Triage note is stale. |
| CVE-2022-22965 | `org.springframework/spring-beans` (Spring4Shell) | `no_flows_source_present` | 2 sources found, **0 sinks**. AI fixture uses `BeanWrapperImpl.setPropertyValue("password", password)`; the sink is *any* setter chain reaching `class.module.classLoader.*`. The engine has no property-path-matching sink mode. | **Defer to engine extension** (roadmap Phase E). Adding `*.setPropertyValue(*)` as a blanket sink would have unacceptable FPs on every legitimate Spring binder call. |
| CVE-2022-22978 | `org.springframework.security/spring-security-web` | `no_flows_no_source` | 0 sources. AI fixture takes a `HttpServletRequest request` parameter directly (no accessor call) and passes it to `matcher.matches(request)`. Engine sources are call-shape (`request.getParameter(*)`), not parameter-type. vuln_class is `auth_bypass` — already in the enum (`spec.ts:58`). | **Defer** — even if Agent E3 widens `auth_bypass` enum coverage, the fixture itself doesn't expose a call-shape source. Lift requires a *parameter-type source* mode or rewriting the AI prompt to emit `request.getRequestURI()`-style accesses. |
| CVE-2023-44483 | `org.apache.santuario/xmlsec` | `no_flows_no_source` | 1 source, **0 sinks**. AI fixture is `signature.sign(keyData.getBytes())` with `@RequestBody String keyData`. **Fixed in this pass**: added `xmlsec.yaml` modelling `*.sign(*) / *.checkSignatureValue(*) / *.addDocument(*) / *.signElement(*) / Canonicalizer.canonicalize(*)` as `deserialization` sinks. | **Spec lands; AI fixture still won't flip** — see "Engine gap" below. The new fixture pair in `test/taint-engine/fixtures/java-vulns/xmlsec-deserialization-{vuln,safe}/` validates that the spec *does* flip when bytes flow without an intermediate receiver-call hop, the structural shape we expect on real-world code. |
| CVE-2023-26464 | `log4j/log4j@1.2.17` | `no_flows_no_source` | 1 source, 0 sinks. AI fixture instantiates `SocketAppender` and calls `appender.activateOptions()` — **the tainted `body` parameter never reaches the appender**. The fixture is structurally degenerate. | **Defer (AI fixture defect)**. The real CVE-2023-26464 is a JNDI gadget in `log4j-1.x`'s socket-server. A correct fixture would deserialize from a network socket, not call `activateOptions()` on a fresh appender. No spec change unblocks this — only an AI rerun against a tighter prompt. |
| CVE-2017-12626 | `org.apache.poi/poi` | `vuln_class_out_of_scope` (`out_of_memory`) | 0 sources, 0 sinks. The vuln is a memory-bomb when parsing a malformed `.doc` — DoS by allocation, not taint flow. | **Uncatchable** — POI XML/OLE allocation DoS is not taint-flow shaped; engine has no `dos`/`out_of_memory` class and adding one would muddy the enum (per Wave 10 stance, DoS shape is intentionally OOS). |

## Engine gap exposed by the xmlsec fixture

The AI-generated CVE-2023-44483 fixture passes the tainted bytes through
an intermediate method-on-receiver call:

```java
@PostMapping("/sign")
public String signDocument(@RequestBody String keyData) throws Exception {
    XMLSignature signature = new XMLSignature(null, "http://example.com");
    signature.sign(keyData.getBytes());  // <-- keyData.getBytes() loses taint
    return "signed";
}
```

The Java IR (per `scripts/probe-xmlsec-ir.ts`) lowers this as:

```
source       keyData
call         keyData.getBytes   target=<arg0@2>  args=[]  argTexts=[]
call         signature.sign     target=-         args=[<arg0@2>]
```

The `keyData.getBytes` call has zero recorded args (the receiver isn't
modeled as an argument), so `<arg0@2>` is **never tainted**. Sink-match
on `signature.sign(<arg0@2>)` therefore sees no tainted argument and
no flow is emitted.

This is a **receiver-taint propagation gap in `propagate-core.ts`** —
the engine's `case 'call'` block (lines 200–280) over-approximates
external calls by propagating the first tainted positional argument to
the target, but does not consider the *receiver* of a method invocation.
Fixing it would require either:

1. The Java IR lowerer emitting an implicit `receiverLocal` slot on
   every `method_invocation` step, with the propagator widening
   external-call taint propagation to include it.
2. A targeted "receiver-pass-through" sink list (`String.getBytes`,
   `String.getBytes(*)`, `String.toCharArray`, etc.) modeled as
   wildcard call-source patterns in `java-stdlib.yaml`.

Option 2 is the spec-layer-only fix and could land independently. It
would re-taint the `<arg0@2>` temp via the source-match branch
(`matchCallSourcePattern`) and unblock at least this CVE's flow. **Out
of scope for this pass** — the receiver-taint gap is cross-cutting and
should be handled deliberately, not as a Text4Shell-side fix.

## Coverage emitted by `xmlsec.yaml`

The new spec is intentionally over-approximating in the Wave 10 style:

- **Five sink patterns** (`*.sign(*)`, `*.checkSignatureValue(*)`,
  `*.addDocument(*)`, `*.signElement(*)`, `Canonicalizer.canonicalize(*)`)
  all under `vuln_class: deserialization` (closest fit in the enum —
  the engine does not include `xxe` / `xml_signature_wrapping`; the
  jackson family established `deserialization` as the "attacker-shaped
  serialised bytes consumed by a library" bucket).
- **`argument_indices: []`** so any tainted argument fires, matching
  the jackson/commons-text precedent.
- **No sources / no sanitizers** — Spring's `@RequestBody`,
  JAX-RS / Quarkus / Micronaut parameter annotations, and
  `HttpServletRequest.getParameter*` already cover sources via
  `spring-boot.yaml` / `quarkus.yaml` / `micronaut.yaml`.

The fixture pair `xmlsec-deserialization-{vuln,safe}/` exercises the
"`@RequestBody byte[] body → XmlSigner.sign(body) → signature.sign(bytes)`"
path — the structural variant the engine *can* propagate today.

## Maven recall after this pass

| Layer | Before | After |
|---|---|---|
| 88-CVE iterate (AI fixture) maven | 10/16 = 62.5% | 10/16 = 62.5% (no AI-side lift — see receiver gap) |
| `taint-engine:recall` java fixtures | 12/12 | 14/14 |
| Engine-side coverage of CVE-2023-44483-shaped flows | none | spec lands; fires on direct-bytes shape |

The headline AI-fixture validation rate stays flat because the receiver
gap blocks lift on the specific Qwen-emitted fixture. Estimated lift if
the receiver-taint engine gap closes: **+1 maven CVE → 11/16 = 68.8%**.
The remaining four (Spring4Shell, Spring Security auth bypass, log4j-1.x
SocketAppender, POI memory bomb) require either engine extensions
(property-path matching, parameter-type sources) or rejection as
non-taint-modelable — and three of those four are tagged in the roadmap
as Phase E / Phase F work.

## Files touched in this pass

- `depscanner/src/taint-engine/framework-models/xmlsec.yaml` (new)
- `depscanner/test/taint-engine/fixtures/java-vulns/xmlsec-deserialization-vuln/` (new)
- `depscanner/test/taint-engine/fixtures/java-vulns/xmlsec-deserialization-safe/` (new)
- `depscanner/test/taint-engine-java.test.ts` (one entry appended)
- `depscanner/scripts/probe-java-fixtures.ts` (new diagnostic tool)
- `depscanner/scripts/probe-xmlsec-ir.ts` (new diagnostic tool)
