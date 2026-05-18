# jackson / unreachable — same CVE-2017-7525 family, no taint path

- **Vulnerable dep:** `com.fasterxml.jackson.core:jackson-databind:2.8.8` (pinned identically to the reachable fixture).
- **Why unreachable:** the controller has no `@RequestBody` (or any other taint-introducing binding); the only `readValue` call is against a hardcoded JSON string. `enableDefaultTyping` is **not** called, so even the over-approximate Jackson sink would be safe.
- **Expected verdict:** no `deserialization` flow.
