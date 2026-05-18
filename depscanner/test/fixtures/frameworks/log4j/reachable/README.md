# log4j / reachable — CVE-2021-44228 (Log4Shell)

- **Vulnerable dep:** `org.apache.logging.log4j:log4j-core:2.14.1`
- **Sink:** `AuditController.java` — `logger.info(userAgent)` where `userAgent` originates from `@RequestHeader("User-Agent")`. Log4j 2.x < 2.15.0 evaluates `${jndi:...}` lookups embedded in the message string, turning an attacker-controlled header into a remote class-load primitive.
- **Entry point:** `@RestController` + `@GetMapping("/audit")`, taking `@RequestHeader("User-Agent") String ua`.
- **Expected vuln_class:** `code_injection` (per framework-models/log4j.yaml; existing taxonomy reused, no enum change).
- **Family:** CVE-2021-44228 / CVE-2021-45046 / CVE-2021-45105 / CVE-2021-44832.
- **Expected verdict:** `data_flow` once dep-scan reports the CVE against this pinned version.
