# spring / unreachable — CVE-2022-22965

- **Vulnerable dep:** `spring-webmvc:5.3.16` (declared, no controller mappings).
- **Why unreachable:** no `@RestController`, no `@RequestMapping` family methods.
- **Expected verdict:** `module`.
