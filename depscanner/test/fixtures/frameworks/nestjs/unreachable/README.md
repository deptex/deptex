# nestjs / unreachable — CVE-2022-24999 (qs prototype pollution / DoS)

- **Vulnerable dep:** `qs@6.5.2` (imported, only `qs.formats` constant referenced).
- **Why unreachable:** the vulnerable `qs.parse` API is never called.
- **Expected verdict:** `module`.
