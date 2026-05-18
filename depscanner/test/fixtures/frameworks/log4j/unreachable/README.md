# log4j / unreachable — same dep pinned, no user-input reaches the logger

- **Vulnerable dep:** `org.apache.logging.log4j:log4j-core:2.14.1` (same as reachable/)
- **Layout:** `@RestController` defines a `/audit` route, but the handler logs only a fixed constant string. The `@RequestHeader("User-Agent")` parameter is dropped on the floor — no taint flow reaches `logger.info()`.
- **Expected verdict:** `module` (dep imported but no taint flow into a known sink).
