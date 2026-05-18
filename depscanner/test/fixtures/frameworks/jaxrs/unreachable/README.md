# jaxrs / unreachable — CVE-2022-1471

- **Vulnerable dep:** `snakeyaml:1.30` (declared, never imported in source).
- **Why unreachable:** resource class has no `@GET`/`@POST` methods; snakeyaml never invoked.
- **Expected verdict:** `module`.
