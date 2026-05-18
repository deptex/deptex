# quarkus / unreachable — CVE-2023-2974

- **Vulnerable dep:** `quarkus-resteasy:2.16.6.Final` (no annotated methods).
- **Why unreachable:** zero `@GET`/`@POST` methods; no resteasy-client call.
- **Expected verdict:** `module`.
