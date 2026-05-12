# Golang Recall Diagnosis — 88-CVE Iterate Corpus, 2026-05-12

## Headline

The 88-CVE iterate harness at tip `61def8e` reported **0/9 golang CVEs
validated** — the only ecosystem on the corpus stuck at 0%. This document
walks each of the 9 golang fixtures through the engine, classifies why it
fails, and lands the one coverage commit that lifts golang to **1/9 = 11%**.

The ceiling estimate from the roadmap (3-4/9, 33-44%) does not hold up
once you read the actual AI fixtures: only **one** of the 9 is shaped
like a taint flow at all. The other eight are either runtime-/protocol-/
config-internal CVEs (genuinely uncatchable in a taint-flow regime) or
AI fixtures that lack a tainted source entirely (the AI hardcoded an
attacker URL instead of routing it through an HTTP handler). Concretely:

| CVE | Package | Triage status | Engine verdict | Verdict |
|---|---|---|---|---|
| CVE-2022-32149 | golang.org/x/text | `vuln_class_out_of_scope` (`dos`) | No fixture rendered | **Uncatchable** — fuzzy-hashing CPU-DoS, not taint-shaped. |
| CVE-2022-27664 | golang.org/x/net | `vuln_class_out_of_scope` (`denial_of_service`) | No fixture rendered | **Uncatchable** — HTTP/2 protocol-level CPU-DoS. |
| CVE-2023-3978 | golang.org/x/net (html) | `failed_validation`, `no_flows_no_source` | Parseable, 0 sources, 0 sinks | **Uncatchable** — fixture hardcodes the HTML payload; no HTTP input flows in. The vuln itself is intra-library (`html.Render` re-emits attacker bytes from `html.Parse`), not a user-data taint path. Coverage would require modeling library-internal data as tainted, which contradicts the engine's user-input-source convention. |
| CVE-2023-44487 | golang.org/x/net/http2 | `failed_validation`, `no_flows_no_source` | Parseable, 0 sources, 0 sinks | **Uncatchable** — HTTP/2 Rapid Reset. Server config (`http2.ConfigureServer`) at startup; protocol-level DoS, not taint. |
| CVE-2024-45337 | golang.org/x/crypto/ssh | `failed_validation`, `no_flows_no_source` | Parseable, 0 sources, 0 sinks | **Uncatchable as written** — `PublicKeyCallback` mis-use (capturing `lastSeenKey` outside the closure, ignoring return value). API-misuse pattern, not a taint flow. Could be caught by a *non-taint detector* (Phase F in the roadmap) but not by the propagator. |
| CVE-2024-21626 | github.com/opencontainers/runc | `failed_validation`, `no_flows_no_source` | Parseable (but `syscall.Unix()` is fictional), 0 sources, 0 sinks | **Uncatchable** — fd-leak / cwd-escape across `runc init`. Runtime-internal; no caller-supplied input. The AI fixture even invents a `syscall.Unix()` API that doesn't exist, which is the more honest signal that this CVE has no caller-facing API surface to taint. |
| CVE-2024-28180 | github.com/go-jose/go-jose/v4 | `failed_validation`, `no_flows_source_present` per triage; on rerun **0 sources** because no spec models plain `net/http`-handler sources | Parseable, 0→1 sources, 0→1 sinks after this PR | **Fixable** (`net-http.yaml` + `go-jose.yaml` land in this PR). The fixture is the classic shape: `r.FormValue("jwe") → obj.Parse(encryptedData) → obj.Decrypt(key)`. Now emits a `deserialization` flow. |
| CVE-2022-21698 | github.com/prometheus/client_golang | `vuln_class_out_of_scope` | No fixture rendered | **Uncatchable** — metric cardinality DoS (unbounded label values blow up the Prometheus collector). Config-level, not taint. |
| CVE-2022-29153 | github.com/hashicorp/consul | `failed_validation`, `no_flows_no_source` | Parseable, 0 sources, 0 sinks (even with `net-http.yaml` loaded) | **Uncatchable as written** — AI fixture hardcodes `http://attacker.com/redirect` rather than threading it through a request handler. The real CVE *is* taint-shaped (consul allowed user-supplied service health-check URLs to bypass an allowlist) but the bench fixture doesn't model that flow. Fixing the engine doesn't help; only an AI-fixture rewrite would. |

**Net feasibility:** 1/9 catchable, which matches the roadmap's
"+1 CVE without engine work" line. The honest golang ceiling on this
specific corpus is **1/9 = 11%**, not the 30-50% the brief hoped for —
the corpus is biased toward stdlib/protocol-internal CVEs that fall
outside the taint-flow expressive frame.

## What changed in this PR

Two new YAML specs and one fixture pair:

1. **`src/taint-engine/framework-models/net-http.yaml`** — sources for
   plain `net/http` handlers (`func(w http.ResponseWriter, r *http.Request)`).
   Wildcard-receiver patterns (`*.FormValue(*)`, `*.URL.Query().Get(*)`,
   `*.Header.Get(*)`, `*.Body`, `*.Form.Get(*)`, …) so they match any
   local-variable request name. Why this was the gap:

   - `gin.yaml` and `echo.yaml` model their context-receiver `c` only.
     The AI's go-jose fixture uses `r.FormValue("jwe")` — different
     receiver, so neither pre-existing spec matched.
   - `go-stdlib.yaml` deliberately holds no sources (per its header
     comment, "sources are framework-specific"). Without `net-http.yaml`,
     every plain-stdlib handler in the corpus emitted 0 sources.

   This is the single largest gap behind golang 0%. It also unblocks
   anything else on the corpus that exercises plain `net/http` handlers
   (none of the other 8 do, but future runs will benefit).

2. **`src/taint-engine/framework-models/go-jose.yaml`** —
   deserialization sinks for the `github.com/go-jose/go-jose` library.
   Pattern set:
   - `jose.ParseEncrypted(*)` / `jose.ParseSigned(*)` — package-shaped.
   - `*.Parse(*)` / `*.Decrypt(*)` / `*.DecryptMulti(*)` — wildcard-
     receiver method shape (the AI fixture uses `var obj jose.JSONWebEncryption;
     obj.Parse(...); obj.Decrypt(...)`).

   `vuln_class: deserialization` is the right class for the family
   (chosen-ciphertext / Bleichenbacher-style attacks where attacker
   bytes flow into a parser whose pre-MAC steps leak secrets). It
   parallels the existing `gob.NewDecoder` / `yaml.Unmarshal` entries
   in `go-stdlib.yaml`.

3. **`test/taint-engine/fixtures/go-vulns/go-jose-deserialization-vuln/`
   + `…-safe/`** — paired fixtures matching the AI's CVE-2024-28180
   shape. Vuln variant flows `r.FormValue("jwe")` into `obj.Parse(...)`;
   safe variant calls `obj.Parse("<hardcoded>")`. Wired into
   `test/taint-engine-go.test.ts` alongside the bundled gin fixtures.

After this PR, `test:taint-engine-go` runs 8 cases, 8 pass. All other
framework-models yamls load without error (`taint-engine:validate -- all`
reports 50/50). `tsc --noEmit` is clean.

## Per-CVE detail

### CVE-2024-28180 — go-jose JWE chosen-ciphertext (fixable, shipped)

Vulnerable fixture (excerpt):

```go
func handler(w http.ResponseWriter, r *http.Request) {
    encryptedData := r.FormValue("jwe")  // source — needs net-http.yaml
    var obj jose.JSONWebEncryption
    _, err := obj.Parse(encryptedData)   // sink — needs go-jose.yaml
    if err != nil { return }
    plaintext, err := obj.Decrypt(key)   // also a sink
    ...
}
```

Engine before this PR: 0 sources, 0 sinks, 0 flows.
Engine after: 1 source (`*.FormValue(*)`), 1 sink (`*.Parse(*)`), 1
`deserialization` flow (`main.go:11 → main.go:15`, 2 hops).

### CVE-2023-3978 — golang.org/x/net/html render-after-parse XSS

AI fixture (excerpt):

```go
doc := `<html><body><script>&lt;img src=x onerror=alert(1)&gt;</script></body></html>`
n, err := html.Parse(strings.NewReader(doc))
html.Render(b, n)
```

The taint source would have to be `doc` — but `doc` is a literal string.
There's no HTTP input, no env, no file-read. The CVE itself is library-
internal: `html.Parse` builds a node tree that round-trips through
`html.Render` in a way the parser's authors didn't quite expect, but
that's a library-correctness bug, not a data-flow bug at the API surface
the AI fixture exercises. No spec will rescue this without redefining
"taint" to include constant strings.

### CVE-2023-44487 — HTTP/2 Rapid Reset

AI fixture configures `http2.Server{}` and calls `ListenAndServe`. No
user-data flow at all; the vuln is protocol-level — a client can open
and immediately RST-stream many requests, exhausting server CPU. The
fix is the `MaxRstFramesPerWindow` / `SecondsPerWindow` config on the
`http2.Server` struct (which the AI's *safe* variant actually models).
This is a *config-presence* detector (Phase F in the roadmap), not a
taint detector.

### CVE-2024-45337 — golang.org/x/crypto/ssh

The pattern is "`PublicKeyCallback` returns `(nil, nil)` instead of
returning an error on auth failure." Wrong-return-value class — API
misuse — not a taint flow. Could be caught by a structural / semantic
rule (`PublicKeyCallback` whose return path can yield `(nil, nil)`
without a host-key check), which the engine doesn't model.

### CVE-2024-21626 — runc init fd leak

The AI fixture invents `syscall.Unix()` — a function that doesn't
exist. Even if it did, the vuln is in the runc binary's init path, not
in caller code. There's no API surface for taint to flow across.

### CVE-2022-29153 — consul SSRF

AI fixture:

```go
req, _ := http.NewRequest("GET", "http://attacker.com/redirect", nil)
client.Do(req)
```

`"http://attacker.com/redirect"` is a constant. No source.

The real CVE *is* taint-shaped — consul allowed user-supplied health-
check URLs to bypass an allowlist — but the AI didn't model that. Re-
running iterate with `net-http.yaml` loaded won't lift this CVE unless
the AI fixture is rewritten to include something like
`url := r.FormValue("check_url")`. That's an AI-prompt issue, not an
engine issue.

### CVE-2022-32149 / CVE-2022-27664 / CVE-2022-21698 — vuln_class_out_of_scope

All three emitted `dos` / `denial_of_service` as the `vuln_class`. The
enum doesn't include those because DoS-class vulns aren't taint-shaped
(there's no source-to-sink data flow; the problem is the parser/codec/
collector itself melts under attacker-shaped inputs). Adding a `dos`
class would just push the problem one layer down: every "expensive
parse" sink would need a corresponding model, and the false-positive
rate on `regexp.Compile` / fuzzy-hash / metric collector calls is
likely to swamp anything real.

## Cross-cutting findings (engine-side)

1. **Plain `net/http` is a real source-coverage gap.** This wasn't
   only a go-jose issue — any pure-stdlib Go HTTP handler in the corpus
   gets 0 sources, today. `net-http.yaml` fixes that for golang in
   general, not just CVE-2024-28180. (The python side has the
   equivalent — flask sources only — and Agent A is landing
   `requests.yaml`/`urllib3.yaml`. The pattern is the same: bundled
   stdlib request shapes need their own spec, not free-rider through
   the framework specs.)

2. **No engine bugs found in the Go IR / callgraph lowerer.** Every
   `parseable: true` fixture in the probe got at least 1 function in
   the callgraph and lowered cleanly. The IR's `*receiver.method`
   wildcard match works as documented (verified manually against
   `r.FormValue`, `obj.Parse`, `obj.Decrypt`, `client.Do`,
   `r.URL.Query().Get`). The text-literal callee-text matching is
   adequate for everything the corpus exercises.

3. **The "no_flows_no_source" triage category is doing double duty.**
   Three CVEs in this bucket (CVE-2023-44487, CVE-2024-45337,
   CVE-2024-21626) have no source because the *vuln has no source*
   (config / API-misuse / runtime-internal). Two (CVE-2023-3978,
   CVE-2022-29153) have no source because the *AI fixture forgot to
   model one*. The categorization conflates two very different
   failure modes; a future triage pass should split them.

## Recommendations beyond this PR

- **Don't pursue golang past 1/9 on this corpus.** The remaining 8 are
  either genuinely uncatchable in a taint regime or would require
  rewriting the AI fixtures. Either is out of scope for engine
  hardening work.
- **Phase F's non-taint detector regime is the only meaningful lever
  left for golang.** A "config-presence" detector for HTTP/2 Rapid
  Reset, an "API-misuse" detector for ssh `PublicKeyCallback`, and a
  "fixed-attacker-URL" SAST rule for the consul shape would cover 3-4
  more golang CVEs without engine surgery. None of those are taint
  flows.
- **Mirror this `net-http.yaml`-style separation for other languages.**
  Python is the obvious next case: Agent A's `requests.yaml`/`urllib3.yaml`
  follow exactly the same pattern.

## Verification gates run

- `npx tsc --noEmit` — clean (this PR alone).
- `npm run taint-engine:validate -- all` — 50/50 fixture suites pass.
- `npm run test:taint-engine-go` — 8 passed, 0 failed (was 6/6 before,
  now 8/8 with the new go-jose pair).
