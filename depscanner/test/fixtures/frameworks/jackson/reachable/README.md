# jackson / reachable — CVE-2017-7525 (jackson-databind polymorphic deser)

- **Vulnerable dep:** `com.fasterxml.jackson.core:jackson-databind:2.8.8`
- **Sink:** `IngestController.java` — `mapper.readValue(body, Object.class)` where the `ObjectMapper` was constructed with `enableDefaultTyping()`. Polymorphic typing turns an attacker-controlled `@class` discriminator into a gadget-chain RCE primitive.
- **Entry point:** `@RestController` + `@PostMapping("/ingest")`, taking `@RequestBody String body`.
- **Expected vuln_class:** `deserialization` (per framework-models/jackson.yaml).
- **Family:** CVE-2017-7525 / CVE-2018-7489 / CVE-2019-12384 / CVE-2019-14439 / CVE-2020-9548 (and dozens of jackson-databind gadget-chain CVEs through 2.9.x–2.13.x).
- **Expected verdict:** `data_flow` once dep-scan reports a polymorphic-deser CVE against this pinned version.
