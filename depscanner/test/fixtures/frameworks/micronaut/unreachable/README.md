# micronaut / unreachable — CVE-2023-25569

- **Vulnerable dep:** `io.micronaut:micronaut-http-server:3.7.4` (controller class only).
- **Why unreachable:** no `@Get`/`@Post` route methods; no HTTP entry.
- **Expected verdict:** `module`.
